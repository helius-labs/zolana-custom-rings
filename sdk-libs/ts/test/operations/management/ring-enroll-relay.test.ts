import { addressBytes, compileUnsignedTransaction, encodeBase58 } from "@heliuslabs/spr/internal";
import type { Instruction } from "@heliuslabs/spr/interface";
import {
  createKeyPairSignerFromPrivateKeyBytes,
  getBase58Encoder,
  getBase64Decoder,
  getBase64Encoder,
  verifySignature,
  type Address,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import {
  enrollInstruction,
  ENROLL_TAG,
  type EnrollmentSeal,
} from "../../../src/operations/management/enrollment.js";
import {
  prepareEnrollmentRelay,
  prepareEnrollRelay,
} from "../../../src/operations/management/enroll-relay.js";
import { SIZE_PROBE_LIFETIME } from "../../../src/operations/workflow/compile.js";
import {
  ENROLL_COMPUTE_UNITS,
  relayEnrollInstruction,
  type RelayEnrollInputs,
} from "../../../src/protocol/ring-rpc/relay-enroll-inputs.js";
import type { RelayStatus } from "../../../src/protocol/ring-rpc/ring-rpc-types.js";
import { PendingRelaySignature, type RingRelayClient } from "../../../src/rpc/relay.js";
import { filled, ringFixture } from "../../helpers/ring-pipeline.js";
import { withConfirmedReads } from "../../helpers/clients.js";

const address = (byte: number): Address => encodeBase58(new Uint8Array(32).fill(byte)) as Address;
const FEE_PAYER = address(0x44);
const REGISTRY = address(0x55);
const quote = { feePayer: FEE_PAYER, validUntilSlot: 100n };
const SEAL: EnrollmentSeal = {
  nullifierPk: filled(1),
  listTag: filled(2),
  ephU: filled(3),
  ciphertext: new Uint8Array(64).fill(4) as EnrollmentSeal["ciphertext"],
};
const ownerSigner = () => createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(1));

function inputsOf(owner: Address): RelayEnrollInputs {
  return {
    ringProgramId: address(0x90),
    owner,
    trackingRegistry: REGISTRY,
    instructionData: Uint8Array.of(ENROLL_TAG, 1, 2),
  };
}

function messageOf(instruction: Instruction, units = ENROLL_COMPUTE_UNITS): Uint8Array {
  const { messageBytes } = compileUnsignedTransaction({
    feePayer: FEE_PAYER,
    lifetime: SIZE_PROBE_LIFETIME,
    instructions: [instruction],
    computeUnitLimit: units,
  });
  return new Uint8Array(messageBytes);
}

function relayAnswering(message: Uint8Array, relayId: string) {
  return {
    getRelayQuote: vi.fn(),
    getRelayStatus: vi.fn(),
    prepareRelay: vi.fn(async () => ({
      step: "signMessage",
      relayId,
      message: getBase64Decoder().decode(message),
    })),
    submitRelay: vi.fn(async (): Promise<RelayStatus> => ({ status: "awaitingSignature" })),
  } as unknown as RingRelayClient;
}

async function signed(answer: (honest: Instruction) => Instruction, units?: number) {
  const owner = await ownerSigner();
  const inputs = inputsOf(owner.address);
  const prepared = await prepareEnrollRelay({ inputs, owner, quote });
  const message = messageOf(answer(await relayEnrollInstruction(inputs, FEE_PAYER)), units);
  const relay = relayAnswering(message, prepared.relayId());
  const pending = await prepared.send(relay);
  if (!(pending instanceof PendingRelaySignature)) throw new Error("the owner signs");
  return pending.sign(relay, owner);
}

const refused = (mismatch: string) => ({
  code: "RING_RELAY_MESSAGE_INVALID",
  details: { mismatch },
});

describe("relayed enrollment", () => {
  it("signs the enrollment the owner proved with its real key", async () => {
    const owner = await ownerSigner();
    const inputs = inputsOf(owner.address);
    const prepared = await prepareEnrollRelay({ inputs, owner, quote });
    const message = messageOf(await relayEnrollInstruction(inputs, FEE_PAYER));
    const relay = relayAnswering(message, prepared.relayId());
    const pending = await prepared.send(relay);
    if (!(pending instanceof PendingRelaySignature)) throw new Error("the owner signs");
    await expect(pending.sign(relay, owner)).resolves.toEqual({ status: "awaitingSignature" });
    const signature = vi.mocked(relay.submitRelay).mock.calls[0]?.[0].signature;
    expect(
      await verifySignature(
        owner.keyPair.publicKey,
        new Uint8Array(getBase58Encoder().encode(signature as string)) as never,
        message,
      ),
    ).toBe(true);
  });

  it("names the accounts the enroll instruction names", async () => {
    const owner = await ownerSigner();
    const built = await enrollInstruction(
      {
        payer: FEE_PAYER,
        owner: owner.address,
        trackingRegistry: REGISTRY,
        seal: SEAL,
        viewingU: filled(5),
      },
      withConfirmedReads({ getAccount: async () => undefined }),
    );
    const relayed = await relayEnrollInstruction(inputsOf(owner.address), FEE_PAYER);
    expect(relayed.accounts).toEqual(built.accounts);
    expect(relayed.programAddress).toBe(built.programAddress);
  });

  it("refuses a swapped account with Accounts", async () => {
    await expect(
      signed((honest) => ({
        ...honest,
        accounts: (honest.accounts ?? []).map((meta) =>
          meta.address === REGISTRY ? { ...meta, address: address(0x56) } : meta,
        ),
      })),
    ).rejects.toMatchObject(refused("Accounts"));
  });

  it("refuses a changed byte with Data", async () => {
    await expect(
      signed((honest) => {
        const data = Uint8Array.from(honest.data ?? []);
        data[1] = (data[1] ?? 0) ^ 1;
        return { ...honest, data };
      }),
    ).rejects.toMatchObject(refused("Data"));
  });

  it("refuses another program and a higher budget", async () => {
    await expect(
      signed((honest) => ({ ...honest, programAddress: address(0x57) })),
    ).rejects.toMatchObject(refused("Program"));
    await expect(signed((honest) => honest, ENROLL_COMPUTE_UNITS + 1)).rejects.toMatchObject(
      refused("Budget"),
    );
  });

  it("refuses an owner that is not the signer", async () => {
    const owner = await ownerSigner();
    await expect(
      prepareEnrollRelay({ inputs: inputsOf(address(9)), owner, quote }),
    ).rejects.toMatchObject(refused("Signer"));
  });

  it("refuses a payer the quote does not name", async () => {
    const owner = await ownerSigner();
    await expect(
      prepareEnrollmentRelay(
        {
          ringProgramId: address(0x90),
          enroll: {
            payer: address(0x45),
            owner: owner.address,
            trackingRegistry: REGISTRY,
            seal: SEAL,
            viewingU: filled(5),
          },
          owner,
          quote,
        },
        withConfirmedReads({ getAccount: async () => undefined }),
      ),
    ).rejects.toMatchObject({ code: "RING_RELAY_PAYER_MISMATCH" });
  });

  it("carries a built enrollment to the relay under the ring's registry", async () => {
    const owner = await ownerSigner();
    const fixture = await ringFixture();
    const prepared = await prepareEnrollmentRelay(
      {
        ringProgramId: fixture.ringProgramId,
        enroll: {
          payer: FEE_PAYER,
          owner: owner.address,
          trackingRegistry: REGISTRY,
          seal: SEAL,
          viewingU: filled(5),
        },
        owner,
        quote,
      },
      fixture.client,
    );
    expect(prepared.request.ring).toBe(fixture.ringProgramId);
    expect(prepared.request.intent.operation).toBe("enroll");
    const { intent } = prepared.request;
    if (intent.operation !== "enroll") throw new Error("an enroll relay");
    const wire = new Uint8Array(getBase64Encoder().encode(intent.proofInputs));
    expect(wire.subarray(64, 96)).toEqual(addressBytes(fixture.trackingRegistry));
  });
});
