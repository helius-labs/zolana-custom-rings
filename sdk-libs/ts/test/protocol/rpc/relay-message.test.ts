/** Refuses a relay message that moves more than the request, against the Rust check's vectors. */
import { readFileSync } from "node:fs";

import {
  getBase58Encoder,
  getBase64Encoder,
  type Address,
  type TransactionPartialSigner,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import {
  DepositAsset,
  type Bytes16,
  type Bytes32,
  type Bytes33,
} from "@heliuslabs/zolana/interface";
import type { indexerTypes } from "@heliuslabs/zolana/internal";
import { ShieldedAddress } from "@heliuslabs/zolana/keypair";

import {
  checkRelayMessage,
  expectedDelegate,
  expectedDeposit,
  type ExpectedRelayMessage,
} from "../../../src/rpc/relay-message.js";
import { PendingRelaySignature, type RingRelayClient } from "../../../src/rpc/relay.js";
import type {
  PrepareAuthorityTransferRequest,
  RelayStatus,
} from "../../../src/protocol/ring-rpc/ring-rpc-types.js";

await initializePoseidon();

const base58 = getBase58Encoder();
const base64 = getBase64Encoder();

interface MessageCase {
  readonly name: string;
  readonly message: string;
  readonly verdict: string;
}

interface Vector<R> {
  readonly request: R;
  readonly cases: readonly MessageCase[];
}

interface DepositRequest {
  readonly ring: Address;
  readonly feePayer: Address;
  readonly tree: Address;
  readonly depositor: Address;
  readonly viewTag: string;
  readonly ownerUtxoHash: string;
  readonly amount: number;
  readonly ringDataHash: string;
  readonly txViewingPk: string;
  readonly salt: string;
  readonly ciphertext: string;
}

interface DelegateRequest {
  readonly prepare: {
    readonly ring: Address;
    readonly delegate: Address;
    readonly transfer: {
      readonly source: string;
      readonly mint: Address;
      readonly payments: readonly { readonly recipient: string; readonly amount: number }[];
    };
  };
  readonly feePayer: Address;
}

function vector<R>(name: string): Vector<R> {
  return JSON.parse(
    readFileSync(new URL(`../../../../../test-vectors/rpc/${name}`, import.meta.url), "utf8"),
  ) as Vector<R>;
}

function hex(text: string): Uint8Array {
  return Uint8Array.from(text.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

function deposit(request: DepositRequest): Promise<ExpectedRelayMessage> {
  return expectedDeposit({
    ringProgramId: request.ring,
    feePayer: request.feePayer,
    tree: request.tree,
    depositor: request.depositor,
    deposit: {
      asset: DepositAsset.sol(),
      viewTag: hex(request.viewTag) as Bytes32,
      ownerUtxoHash: hex(request.ownerUtxoHash) as Bytes32,
      amount: BigInt(request.amount),
      ringDataHash: hex(request.ringDataHash) as Bytes32,
      encrypted: {
        txViewingPublicKey: hex(request.txViewingPk) as Bytes33,
        salt: hex(request.salt) as Bytes16,
        ciphertext: new Uint8Array(base64.encode(request.ciphertext)),
      },
    },
  });
}

function delegate(request: DelegateRequest): Promise<ExpectedRelayMessage> {
  const shielded = (text: string) => ShieldedAddress.fromBytes(new Uint8Array(base58.encode(text)));
  const { prepare } = request;
  return expectedDelegate(
    {
      ring: prepare.ring,
      delegate: prepare.delegate,
      transfer: {
        source: shielded(prepare.transfer.source),
        mint: prepare.transfer.mint,
        payments: prepare.transfer.payments.map((payment) => ({
          recipient: shielded(payment.recipient),
          amount: BigInt(payment.amount),
        })),
      },
    } as unknown as PrepareAuthorityTransferRequest,
    { feePayer: request.feePayer, validUntilSlot: 0n },
  );
}

function verdict(expected: ExpectedRelayMessage, message: string): string {
  try {
    checkRelayMessage(expected, new Uint8Array(base64.encode(message)));
    return "Accepted";
  } catch (error) {
    return String((error as { details?: { mismatch?: unknown } }).details?.mismatch);
  }
}

function message(cases: readonly MessageCase[], name: string): Uint8Array {
  const found = cases.find((entry) => entry.name === name);
  if (found === undefined) throw new Error(`no case ${name}`);
  return new Uint8Array(base64.encode(found.message));
}

/** The signature bytes are the relay's to verify, the check runs before any signer. */
function signer(address: Address): TransactionPartialSigner & { calls: number } {
  const fake = {
    address,
    calls: 0,
    signTransactions: async () => {
      fake.calls += 1;
      return [{ [address]: new Uint8Array(64) }];
    },
  };
  return fake as unknown as TransactionPartialSigner & { calls: number };
}

function relay(): RingRelayClient & { submitRelay: ReturnType<typeof vi.fn> } {
  return {
    getRelayQuote: vi.fn(),
    prepareRelay: vi.fn(),
    getRelayStatus: vi.fn(),
    submitRelay: vi.fn(async (): Promise<RelayStatus> => ({ status: "awaitingSignature" })),
  } as unknown as RingRelayClient & { submitRelay: ReturnType<typeof vi.fn> };
}

const RELAY_ID = "11111111111111111111111111111111" as indexerTypes.Hash;
const deposits = vector<DepositRequest>("relay_deposit_messages.json");
const delegates = vector<DelegateRequest>("relay_delegate_messages.json");

describe("relay message check", () => {
  it.each(deposits.cases)("reaches the Rust verdict on deposit message $name", async (entry) => {
    expect(verdict(await deposit(deposits.request), entry.message)).toBe(entry.verdict);
  });

  it.each(delegates.cases)("reaches the Rust verdict on delegate message $name", async (entry) => {
    expect(verdict(await delegate(delegates.request), entry.message)).toBe(entry.verdict);
  });

  it("refuses a deposit message with an extra SPL transfer from the depositor before signing", async () => {
    const expected = await deposit(deposits.request);
    const depositor = signer(deposits.request.depositor);
    const ringRpc = relay();
    const pending = new PendingRelaySignature(
      RELAY_ID,
      message(deposits.cases, "extraSplTransfer"),
      expected,
    );
    await expect(pending.sign(ringRpc, depositor)).rejects.toMatchObject({
      code: "RING_RELAY_MESSAGE_INVALID",
      details: { mismatch: "Instructions" },
    });
    expect(depositor.calls).toBe(0);
    expect(ringRpc.submitRelay).not.toHaveBeenCalled();
  });

  it("refuses a delegate message with a swapped recipient before signing", async () => {
    const expected = await delegate(delegates.request);
    const delegateSigner = signer(delegates.request.prepare.delegate);
    const ringRpc = relay();
    const pending = new PendingRelaySignature(
      RELAY_ID,
      message(delegates.cases, "swappedRecipient"),
      expected,
    );
    await expect(pending.sign(ringRpc, delegateSigner)).rejects.toMatchObject({
      details: { mismatch: "Recipients" },
    });
    expect(delegateSigner.calls).toBe(0);
  });

  it("signs the honest messages the relay builds", async () => {
    for (const [expected, cases, address] of [
      [await deposit(deposits.request), deposits.cases, deposits.request.depositor],
      [await delegate(delegates.request), delegates.cases, delegates.request.prepare.delegate],
    ] as const) {
      const ringRpc = relay();
      await new PendingRelaySignature(RELAY_ID, message(cases, "honest"), expected).sign(
        ringRpc,
        signer(address),
      );
      expect(ringRpc.submitRelay).toHaveBeenCalledWith(
        expect.objectContaining({ relayId: RELAY_ID, signer: address }),
        undefined,
      );
    }
  });
});
