import { getBase58Decoder, getBase64Decoder, type MessagePartialSigner } from "@solana/kit";
import type { RequestContext, Signature } from "@heliuslabs/spr/interface";
import { signerAddress } from "@heliuslabs/spr/internal";

import { RingError } from "../../protocol/error.js";
import { fetchRingPolicy } from "../../protocol/membership/config.js";
import {
  encodeRelayEnrollInputs,
  enrollRequestDigest,
  type RelayEnrollInputs,
} from "../../protocol/ring-rpc/relay-enroll-inputs.js";
import type { RelayIntent, RelayQuote } from "../../protocol/ring-rpc/ring-rpc-types.js";
import { expectedEnroll, mismatch } from "../../rpc/relay-message.js";
import { PreparedRelay } from "../../rpc/relay.js";
import { signMessage } from "../../rpc/ring-rpc.js";
import { enrollInstruction, type Enroll, type EnrollmentReadClient } from "./enrollment.js";

/** A PDA holds no key to sign here, its program enrolls through CPI. */
export async function prepareEnrollRelay(
  input: Readonly<{
    inputs: RelayEnrollInputs;
    owner: MessagePartialSigner;
    quote: RelayQuote;
  }>,
): Promise<PreparedRelay> {
  const { inputs, owner, quote } = input;
  if (owner.address !== inputs.owner) throw mismatch("Signer");
  const signature = await signMessage(owner, enrollRequestDigest(inputs));
  const intent: RelayIntent = {
    operation: "enroll",
    proofInputs: getBase64Decoder().decode(encodeRelayEnrollInputs(inputs)) as never,
    ownerSignature: getBase58Decoder().decode(signature) as Signature,
  };
  return new PreparedRelay(
    { ring: inputs.ringProgramId, quote, intent },
    await expectedEnroll(inputs, quote.feePayer),
  );
}

export async function prepareEnrollmentRelay(
  input: Readonly<{
    ringProgramId: RelayEnrollInputs["ringProgramId"];
    enroll: Enroll;
    owner: MessagePartialSigner;
    quote: RelayQuote;
  }>,
  client: EnrollmentReadClient,
  context?: RequestContext,
): Promise<PreparedRelay> {
  const { ringProgramId, enroll, owner, quote } = input;
  const payer = signerAddress(enroll.payer);
  if (payer !== quote.feePayer)
    throw new RingError("RING_RELAY_PAYER_MISMATCH", {
      details: { payer, feePayer: quote.feePayer },
    });
  const { tracking } = await fetchRingPolicy(client, ringProgramId, context);
  const proved = await enrollInstruction(
    { ...enroll, trackingRegistry: tracking },
    client,
    context,
  );
  return prepareEnrollRelay({
    inputs: {
      ringProgramId,
      owner: signerAddress(enroll.owner),
      trackingRegistry: tracking,
      instructionData: new Uint8Array(proved.data ?? []),
    },
    owner,
    quote,
  });
}
