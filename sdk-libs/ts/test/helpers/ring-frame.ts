import { SPP_SUPPORTED_SHAPES } from "@heliuslabs/spr/interface";
import type { Bytes16, Bytes32 } from "@heliuslabs/spr/interface";

import { CUSTOM_RING_PROOF_LENGTH } from "../../src/protocol/proof/custom-ring-proof.js";
import {
  OUTPUT_RECORD_LEN,
  PAYLOAD_LENGTH_LEN,
  envelopeRegion,
  recipientKeysLen,
} from "../../src/protocol/codec/ring-disclosure-layout.js";
import { senderBundleLen } from "../../src/protocol/codec/anonymous-delivery.js";
import { RingInstructionTag } from "../../src/protocol/transaction/instruction-tag.js";
import { RING_AUTHORITY_SHAPES } from "../../src/protocol/transaction/spp.js";
import {
  isAnonymousFrame,
  isDelegateRail,
  PLAIN_GROTH16_PROOF_LENGTH,
  ringStreamLayout,
  RingTransactData,
  type RingOutput,
  type RingRail,
} from "../../src/protocol/transaction/transact.js";

export function field(byte: number): Bytes32 {
  const value = new Uint8Array(32);
  value[31] = byte;
  return value as Bytes32;
}

/** A frame of `inputs` and `outputs` the rail's audit key serves, no proof valid. */
export function ringFrame(
  input: Readonly<{
    rail: RingRail;
    inputs: number;
    outputs: number;
    entry?: boolean;
    hasData?: boolean;
    publicOwners?: boolean;
    wideOwners?: boolean;
  }>,
): RingTransactData {
  const { rail, inputs, outputs } = input;
  const entry = input.entry ?? false;
  const hasData = input.hasData ?? false;
  const publicOwners = input.publicOwners ?? false;
  const keyed = isDelegateRail(rail) ? RING_AUTHORITY_SHAPES : SPP_SUPPORTED_SHAPES;
  const shape = keyed.find((entry_) => entry_.inputs >= inputs && entry_.outputs === outputs);
  if (shape === undefined) throw new Error("no shape serves the counts");
  const layout = ringStreamLayout({
    rail,
    nIn: shape.inputs,
    nOut: shape.outputs,
    inputs,
    outputs,
    entry,
    publicOwners,
  });
  const anonymous = isAnonymousFrame(rail);
  const slot = (index: number): RingOutput => {
    const change = anonymous && index === 0;
    return {
      hash: field(10 + index),
      ownerTag: change ? (new Uint8Array(32) as Bytes32) : field(40 + index),
      record: new Uint8Array(OUTPUT_RECORD_LEN).fill(index + 1),
      body: {
        kind: "recipient",
        payload: new Uint8Array(hasData ? PAYLOAD_LENGTH_LEN : 0).fill(index + 101),
      },
    };
  };
  const delegate = isDelegateRail(rail);
  return {
    rail,
    nIn: shape.inputs,
    nOut: shape.outputs,
    proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
    trackingRevision: 7n,
    ...(delegate ? {} : { ownRevision: 1n }),
    splWithdrawalOwners: [],
    approval: 0,
    noSpend: false,
    publicOwners,
    expiryUnixTs: 0,
    txViewingU: field(1),
    salt: new Uint8Array(16).fill(3) as Bytes16,
    extensions: {},
    interfaceTransfers: [],
    hasData,
    entry,
    wideOwners: input.wideOwners ?? false,
    outputs: Array.from({ length: outputs }, (_, index) => slot(index)),
    ...(anonymous
      ? { sender: { tag: field(1), body: new Uint8Array(senderBundleLen({ outputs })) } }
      : {}),
    envelope: new Uint8Array(envelopeRegion(layout).length).fill(3),
    recipientKeys: new Uint8Array(recipientKeysLen(layout)).fill(9),
    privateTxHash: field(4),
    ...(rail === "anonymous" && !publicOwners
      ? { anonymous: { commitment: field(5), commitmentPok: field(6) } }
      : {}),
    sppProof: new Uint8Array(PLAIN_GROTH16_PROOF_LENGTH),
    nullifiers: Array.from({ length: inputs }, (_, index) => field(70 + index)),
    inputTrees: { kind: "one", context: { utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 } },
  };
}

/** The ring program's own instruction data around `frame`. */
export function ringInstructionData(frame: RingTransactData): Uint8Array {
  const tag = isDelegateRail(frame.rail)
    ? RingInstructionTag.authorityTransfer
    : RingInstructionTag.transfer;
  return Uint8Array.of(tag, ...RingTransactData.encode(frame));
}
